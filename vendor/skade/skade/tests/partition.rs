//! Partitioned writes: `create_partitioned_table` + identity-partition `append`
//! tag data files with the partition value (single-partition per commit) and
//! round-trip; a batch spanning partitions is rejected rather than mis-tagged.

use std::sync::Arc;

use anyhow::Result;
use skade::arrow_array::{Int64Array, RecordBatch, StringArray};
use skade::arrow_schema::{DataType, Field, Schema};

fn schema() -> Schema {
    Schema::new(vec![
        Field::new("repo", DataType::Utf8, false),
        Field::new("id", DataType::Int64, false),
    ])
}

fn batch(repo: &str, ids: Vec<i64>) -> Result<RecordBatch> {
    let repos: Vec<&str> = vec![repo; ids.len()];
    Ok(RecordBatch::try_new(
        Arc::new(schema()),
        vec![
            Arc::new(StringArray::from(repos)),
            Arc::new(Int64Array::from(ids)),
        ],
    )?)
}

#[tokio::test]
async fn partitioned_append_round_trips() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh
        .create_partitioned_table("facts", &schema(), &["repo"])
        .await?;

    // One repo per commit — the single-partition shape append commits.
    t.append(&[batch("holger", vec![1, 2, 3])?]).await?;
    t.append(&[batch("znippy", vec![4, 5])?]).await?;

    let all = t.read().await?;
    let total: usize = all.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total, 5, "all rows across both partitions must read back");
    assert_eq!(t.count().await?, 5);
    Ok(())
}

#[tokio::test]
async fn multi_partition_batch_is_rejected() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh
        .create_partitioned_table("facts", &schema(), &["repo"])
        .await?;

    // A batch spanning two partition values must error, not silently mis-tag.
    let mixed = RecordBatch::try_new(
        Arc::new(schema()),
        vec![
            Arc::new(StringArray::from(vec!["holger", "znippy"])),
            Arc::new(Int64Array::from(vec![1i64, 2])),
        ],
    )?;
    let err = t
        .append(&[mixed])
        .await
        .expect_err("multi-partition append must fail");
    assert!(
        err.to_string().contains("multiple"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn empty_partition_cols_is_unpartitioned() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    // Empty partition_cols == create_table: a mixed batch is then fine.
    let mut t = wh.create_partitioned_table("facts", &schema(), &[]).await?;
    t.append(&[batch("holger", vec![1])?]).await?;
    t.append(&[RecordBatch::try_new(
        Arc::new(schema()),
        vec![
            Arc::new(StringArray::from(vec!["a", "b"])),
            Arc::new(Int64Array::from(vec![2i64, 3])),
        ],
    )?])
    .await?;
    assert_eq!(t.count().await?, 3);
    Ok(())
}

/// End-to-end guard on the uniform-collapse partition-scan accelerator: a large
/// single-partition batch must tag every row with the *right* partition value,
/// and a near-uniform batch that differs in a single row must still be rejected
/// (the fast path may not silently accept it). RED-when-broken: a wrong or
/// skipped partition key flips these to failing.
#[tokio::test]
async fn large_uniform_partition_tags_correctly_and_is_filterable() -> Result<()> {
    use skade::ScanFilter;
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh
        .create_partitioned_table("facts", &schema(), &["repo"])
        .await?;

    // A 20k-row single-partition append: exercises the offsets+memcmp fast path.
    t.append(&[batch("znippy", (0..20_000).collect())?]).await?;
    t.append(&[batch("holger", (0..5_000).collect())?]).await?;
    assert_eq!(t.count().await?, 25_000);

    // Partition pruning must resolve the tags: reading the `znippy` partition
    // returns exactly its rows — proves the fast path tagged the value correctly.
    let znippy = t
        .read_filtered(&ScanFilter::eq("repo", "znippy"), &[])
        .await?;
    let got: usize = znippy.iter().map(|b| b.num_rows()).sum();
    assert_eq!(
        got, 20_000,
        "the znippy partition must carry exactly its rows"
    );
    Ok(())
}

#[tokio::test]
async fn near_uniform_batch_differing_one_row_is_rejected() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh
        .create_partitioned_table("facts", &schema(), &["repo"])
        .await?;

    // 4096 rows all "repo0" except the LAST — same length as "repo0", so only the
    // periodicity memcmp (not the length pre-check) can catch it. Must error.
    let mut repos: Vec<&str> = vec!["repo0"; 4096];
    *repos.last_mut().unwrap() = "repo9";
    let ids: Vec<i64> = (0..4096).collect();
    let mixed = RecordBatch::try_new(
        Arc::new(schema()),
        vec![
            Arc::new(StringArray::from(repos)),
            Arc::new(Int64Array::from(ids)),
        ],
    )?;
    let err = t
        .append(&[mixed])
        .await
        .expect_err("a batch spanning two partitions must fail, not mis-tag");
    assert!(
        err.to_string().contains("multiple"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[tokio::test]
async fn ingest_parallel_partitioned_round_trips() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh
        .create_partitioned_table("facts", &schema(), &["repo"])
        .await?;

    // 8 groups → 8 parquet files, all single-partition (repo = holger),
    // encoded across cores, committed every 3 files.
    let groups: Vec<Vec<RecordBatch>> = (0..8)
        .map(|k| vec![batch("holger", (k * 10..k * 10 + 10).collect()).unwrap()])
        .collect();
    let stats = t.ingest_parallel(groups, 3).await?;
    assert_eq!(stats.rows, 80);
    assert_eq!(t.count().await?, 80, "all parallel-encoded rows read back");
    Ok(())
}

#[tokio::test]
async fn ingest_parallel_unpartitioned_round_trips() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.create_table("facts", &schema()).await?;
    let groups: Vec<Vec<RecordBatch>> = (0..5)
        .map(|k| vec![batch("any", (k * 100..k * 100 + 100).collect()).unwrap()])
        .collect();
    let stats = t.ingest_parallel(groups, 2).await?;
    assert_eq!(stats.rows, 500);
    assert_eq!(t.count().await?, 500);
    Ok(())
}

#[tokio::test]
async fn new_tables_are_format_v3() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let t = wh.create_table("plain", &schema()).await?;
    assert_eq!(
        t.inner().metadata().format_version(),
        iceberg::spec::FormatVersion::V3
    );
    let p = wh
        .create_partitioned_table("parted", &schema(), &["repo"])
        .await?;
    assert_eq!(
        p.inner().metadata().format_version(),
        iceberg::spec::FormatVersion::V3
    );
    Ok(())
}

#[tokio::test]
async fn v3_row_lineage_is_active() -> Result<()> {
    // Row lineage (v3) is automatic on V3 tables: each append advances the
    // table's next_row_id by the rows added. skade writes V3, so it's free.
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.create_table("rl", &schema()).await?;
    assert_eq!(t.inner().metadata().next_row_id(), 0, "INITIAL_ROW_ID");
    t.append(&[batch("x", (0..5).collect())?]).await?;
    assert_eq!(
        t.inner().metadata().next_row_id(),
        5,
        "row lineage advanced by 5 rows"
    );
    t.append(&[batch("y", (0..3).collect())?]).await?;
    assert_eq!(t.inner().metadata().next_row_id(), 8, "and by 3 more");
    Ok(())
}

#[tokio::test]
async fn compression_codecs_round_trip() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let b = batch("nornir", (0..10_000).collect())?;
    for (name, codec) in [
        ("none", skade::Compression::UNCOMPRESSED),
        ("snappy", skade::Compression::SNAPPY),
        ("zstd", skade::Compression::ZSTD(Default::default())),
    ] {
        let mut t = wh.create_table(name, &schema()).await?.compression(codec);
        t.append(&[b.clone()]).await?;
        assert_eq!(t.count().await?, 10_000, "{name} round-trips");
        let rows: usize = t.read().await?.iter().map(|x| x.num_rows()).sum();
        assert_eq!(rows, 10_000, "{name} reads back");
    }
    Ok(())
}

#[tokio::test]
async fn read_columns_projects() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.create_table("p", &schema()).await?; // schema: repo, id
    t.append(&[batch("x", (0..100).collect())?]).await?;
    let cols = t.read_columns(&["id"]).await?;
    assert!(
        cols.iter().all(|b| b.num_columns() == 1),
        "only `id` projected"
    );
    assert_eq!(cols.iter().map(|b| b.num_rows()).sum::<usize>(), 100);
    Ok(())
}

/// GAP 1 — filtered / pushdown read. Inject two repos' rows into an identity-
/// partitioned table, then `read_filtered(ScanFilter::eq("repo", "znippy"))`
/// and assert it returns ONLY the matching repo's rows (the others are pruned),
/// matching nornir's `scan_repo_filtered` reach-through.
#[tokio::test]
async fn read_filtered_returns_only_matching_partition() -> Result<()> {
    use skade::ScanFilter;

    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh
        .create_partitioned_table("facts", &schema(), &["repo"])
        .await?;

    // One commit per repo (single-partition append shape).
    t.append(&[batch("znippy", vec![1, 2, 3])?]).await?; // 3 rows
    t.append(&[batch("holger", vec![4, 5])?]).await?; // 2 rows
    t.append(&[batch("nornir", vec![6, 7, 8, 9])?]).await?; // 4 rows

    // Sanity: an unfiltered read sees everything.
    assert_eq!(t.count().await?, 9);

    // Filtered read: only the `znippy` partition.
    let got = t
        .read_filtered(&ScanFilter::eq("repo", "znippy"), &[])
        .await?;
    let rows: usize = got.iter().map(|b| b.num_rows()).sum();
    assert_eq!(
        rows, 3,
        "pushdown returns ONLY the znippy partition's 3 rows"
    );

    // Assert the actual VALUES: every returned row's repo column == "znippy"
    // and the ids are exactly {1,2,3}.
    let mut ids: Vec<i64> = Vec::new();
    for b in &got {
        let repo_idx = b.schema().index_of("repo")?;
        let id_idx = b.schema().index_of("id")?;
        let repos = b
            .column(repo_idx)
            .as_any()
            .downcast_ref::<StringArray>()
            .expect("repo is Utf8");
        let id_arr = b
            .column(id_idx)
            .as_any()
            .downcast_ref::<Int64Array>()
            .expect("id is Int64");
        for r in 0..b.num_rows() {
            assert_eq!(repos.value(r), "znippy", "no other repo's rows leaked");
            ids.push(id_arr.value(r));
        }
    }
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2, 3], "exactly the znippy ids, nothing else");

    // IN over two repos returns their union (3 + 4 = 7 rows), still excluding holger.
    let got_in = t
        .read_filtered(&ScanFilter::is_in("repo", ["znippy", "nornir"]), &[])
        .await?;
    let in_rows: usize = got_in.iter().map(|b| b.num_rows()).sum();
    assert_eq!(
        in_rows, 7,
        "IN (znippy, nornir) → 3 + 4 rows, holger pruned"
    );

    Ok(())
}

/// GAP 2 — limit / early-break streaming read. Inject many rows, then
/// `read_limited(N)` and assert it returns AT MOST a small whole-batch overage
/// of N (never the full table) — i.e. it stops early instead of materializing
/// everything, matching nornir's `scan_limited`.
#[tokio::test]
async fn read_limited_stops_early_without_full_scan() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.create_table("big", &schema()).await?;

    // 20 data files × 1000 rows = 20_000 rows total, across many parquet files
    // so an early break genuinely avoids reading most of them.
    for k in 0..20 {
        t.append(&[batch("x", (k * 1000..k * 1000 + 1000).collect())?])
            .await?;
    }
    assert_eq!(t.count().await?, 20_000, "all 20k rows are present");

    // Limit to 100. batch_size is clamped to >=256, so the first batch (≤8192,
    // here ≤ a file's 1000 rows) satisfies the limit; we must NOT pull all 20k.
    let limit = 100usize;
    let got = t.read_limited(limit).await?;
    let rows: usize = got.iter().map(|b| b.num_rows()).sum();
    assert!(
        rows >= limit,
        "must return at least the requested {limit} rows"
    );
    assert!(
        rows < 20_000,
        "early break must NOT materialize the whole 20k-row table (got {rows})"
    );
    // Concretely: with 1000-row files it stops after the first file → 1000 rows,
    // an order of magnitude less than the full table.
    assert!(
        rows <= 2000,
        "stops within a batch or two of the limit, not the whole table (got {rows})"
    );

    // limit == 0 falls back to a full scan (the documented escape hatch).
    let all = t.read_limited(0).await?;
    assert_eq!(
        all.iter().map(|b| b.num_rows()).sum::<usize>(),
        20_000,
        "max_rows == 0 reads the whole table"
    );

    Ok(())
}

/// `IN ()` (empty value list) must match NOTHING — not the whole table. The
/// lowering hand-builds an always-false predicate (`col IS NULL AND col IS NOT
/// NULL`), a subtle path: a bug that dropped the filter would wrongly return
/// every row. Locked in for BOTH a partition column (`repo`) and a plain data
/// column (`id`), and contrasted with a non-empty `IN` that DOES match.
#[tokio::test]
async fn empty_in_matches_nothing() -> Result<()> {
    use skade::ScanFilter;

    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh
        .create_partitioned_table("facts", &schema(), &["repo"])
        .await?;

    t.append(&[batch("znippy", vec![1, 2, 3])?]).await?; // 3 rows
    t.append(&[batch("holger", vec![4, 5])?]).await?; // 2 rows
    assert_eq!(t.count().await?, 5, "5 rows present overall");

    // Empty IN on the PARTITION column → zero rows (NOT the whole table).
    let empty_partition = t
        .read_filtered(&ScanFilter::is_in("repo", Vec::<&str>::new()), &[])
        .await?;
    let n: usize = empty_partition.iter().map(|b| b.num_rows()).sum();
    assert_eq!(n, 0, "IN () on repo must match nothing, got {n} rows");

    // Empty IN on a PLAIN DATA column (id) → zero rows too.
    let empty_data = t
        .read_filtered(&ScanFilter::is_in("id", Vec::<i64>::new()), &[])
        .await?;
    let n2: usize = empty_data.iter().map(|b| b.num_rows()).sum();
    assert_eq!(n2, 0, "IN () on id must match nothing, got {n2} rows");

    // Contrast: a NON-empty IN with a value that IS present returns those rows.
    let present = t
        .read_filtered(&ScanFilter::is_in("repo", ["znippy"]), &[])
        .await?;
    let np: usize = present.iter().map(|b| b.num_rows()).sum();
    assert_eq!(
        np, 3,
        "IN (znippy) returns its 3 rows, proving the filter is live"
    );

    // The plan agrees: empty IN prunes to zero planned rows, present prunes to 3.
    let empty_plan = t
        .plan_stats(Some(&ScanFilter::is_in("repo", Vec::<&str>::new())))
        .await?;
    assert_eq!(empty_plan.rows_planned, 0, "empty IN plans zero rows");
    assert_eq!(empty_plan.data_files, 0, "empty IN opens no data files");

    skade::functional_status(
        "skade/read",
        "empty_in_matches_nothing",
        true,
        "IN () on partition + data column yields 0 rows; IN (present) yields the match",
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn ingest_pipelined_round_trips() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    // partitioned (per-file partition through the pipeline) + unpartitioned
    let mut p = wh
        .create_partitioned_table("facts", &schema(), &["repo"])
        .await?;
    let groups: Vec<Vec<RecordBatch>> = (0..8)
        .map(|k| vec![batch("holger", (k * 10..k * 10 + 10).collect()).unwrap()])
        .collect();
    let stats = p.ingest_pipelined(groups, 3, 4).await?; // fpc=3, channel_depth=4
    assert_eq!(stats.rows, 80);
    assert_eq!(p.count().await?, 80, "pipelined partitioned round-trips");

    let mut u = wh.create_table("plain", &schema()).await?;
    let g2: Vec<Vec<RecordBatch>> = (0..5)
        .map(|k| vec![batch("x", (k * 100..k * 100 + 100).collect()).unwrap()])
        .collect();
    u.ingest_pipelined(g2, 2, 2).await?;
    assert_eq!(u.count().await?, 500);
    Ok(())
}
