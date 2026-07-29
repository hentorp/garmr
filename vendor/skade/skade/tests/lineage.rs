//! End-to-end coverage for the `lineage` feature's **emit-on-append hook**: a
//! `LineageSink` attached to a `Table` via `with_lineage_sink` must receive one
//! `Append` lineage fact per committed `append`, carrying the table and the new
//! snapshot id — and the sink's best-effort contract must never fail the write.
//!
//! The isolated `CapturingSink` builder round-trip is unit-tested inside
//! `src/lineage.rs`; THIS drives the real `Table::append` -> `sink.emit` path
//! (the newest surface, whose `skade/lineage sink_emit` functional marker was
//! wired in `b493abb`) that no other test exercises. Each check emits a
//! functional-status row under `--features testmatrix` (korp-collectors pattern).
#![cfg(feature = "lineage")]

use std::sync::Arc;

use anyhow::Result;
use skade::arrow_array::{Int64Array, RecordBatch, StringArray};
use skade::arrow_schema::{DataType, Field, Schema};
use skade::iceberg::TableUpdate;
use skade::lineage::{CapturingSink, DatasetRef, LineageEvent, LineageSink, Operation};

mod common;
use common::emit_for;

/// A sink whose `emit` ALWAYS fails — used to prove the best-effort contract:
/// a sink error must never fail the write. Counts calls so we can assert the
/// hook actually fired.
#[derive(Debug, Default)]
struct FailingSink {
    calls: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl LineageSink for FailingSink {
    async fn emit(&self, _event: &LineageEvent) -> skade::Result<()> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(skade::SkadeError::Other("sink is down".into()))
    }
}

fn schema() -> Schema {
    Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, false),
    ])
}

fn batch(ids: &[i64]) -> Result<RecordBatch> {
    let names: Vec<String> = ids.iter().map(|i| format!("row-{i}")).collect();
    Ok(RecordBatch::try_new(
        Arc::new(schema()),
        vec![
            Arc::new(Int64Array::from(ids.to_vec())),
            Arc::new(StringArray::from(names)),
        ],
    )?)
}

/// One attached sink, two appends → exactly two `Append` facts, each stamped
/// with the table and the snapshot id the commit produced. Best-effort emit
/// never fails the write (the rows are readable afterward).
#[tokio::test]
async fn append_emits_lineage_fact_per_commit() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    let sink = CapturingSink::new();
    let mut t = wh
        .create_table("events", &schema())
        .await?
        .with_lineage_sink(Arc::new(sink.clone()));
    assert!(sink.is_empty(), "no facts before any append");

    // First commit.
    t.append(&[batch(&[1, 2, 3])?]).await?;
    let snap1 = t.current_snapshot_id();
    let after_first = sink.events();
    assert_eq!(after_first.len(), 1, "one append = one lineage fact");
    let e1 = &after_first[0];
    assert_eq!(e1.operation, Operation::Append, "op is Append");
    assert!(
        e1.output.table.ends_with("events"),
        "output names the table"
    );
    assert_eq!(
        e1.output.snapshot_id, snap1,
        "fact carries the new snapshot id"
    );
    assert!(
        e1.output.system.is_none(),
        "in-warehouse output (no cross-system hop)"
    );
    assert!(e1.ts_micros > 0, "timestamp stamped post-commit");

    // Second commit: a fresh snapshot, a second distinct fact.
    t.append(&[batch(&[4, 5])?]).await?;
    let snap2 = t.current_snapshot_id();
    let all = sink.events();
    assert_eq!(all.len(), 2, "second append = second lineage fact");
    assert_eq!(
        all[1].output.snapshot_id, snap2,
        "second fact = second snapshot"
    );
    assert_ne!(snap1, snap2, "each append advances the snapshot");
    assert_ne!(all[0].event_id, all[1].event_id, "facts are process-unique");

    // The best-effort emit did NOT swallow the actual data write.
    assert_eq!(t.count().await?, 5, "all appended rows are readable");

    emit_for(
        "skade/lineage",
        "sink_emit",
        true,
        "2 appends -> 2 Append facts, snapshot ids carried, rows intact",
    );
    Ok(())
}

/// The best-effort contract: a sink whose `emit` returns `Err` must NOT fail the
/// append. The rows still commit and read back, and the (failing) sink was
/// actually invoked once per append — proving the error was swallowed, not that
/// the hook was skipped. Only the success and no-sink paths were covered before.
#[tokio::test]
async fn failing_sink_does_not_fail_write() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    let sink = Arc::new(FailingSink::default());
    let mut t = wh
        .create_table("events", &schema())
        .await?
        .with_lineage_sink(sink.clone());

    // The append MUST succeed despite the sink erroring on emit.
    t.append(&[batch(&[1, 2, 3])?]).await?;
    assert_eq!(
        t.count().await?,
        3,
        "rows committed despite the sink failing"
    );

    // A second append: still fine, and the sink was hit once per append.
    t.append(&[batch(&[4, 5])?]).await?;
    assert_eq!(
        t.count().await?,
        5,
        "second append also survives the sink error"
    );
    assert_eq!(
        sink.calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the failing sink was invoked once per append (error swallowed, not skipped)"
    );

    emit_for(
        "skade/lineage",
        "failing_sink_does_not_fail_write",
        true,
        "sink emit Err swallowed: 2 appends commit, rows readable, sink hit twice",
    );
    Ok(())
}

/// A table with NO sink attached still commits and reads back — the lineage hook
/// is inert when unused (feature on, sink absent).
#[tokio::test]
async fn append_without_sink_is_inert() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;
    let mut t = wh.create_table("events", &schema()).await?;
    t.append(&[batch(&[1, 2, 3, 4])?]).await?;
    assert_eq!(t.count().await?, 4, "unhooked append commits normally");

    emit_for(
        "skade/lineage",
        "hook_inert_without_sink",
        true,
        "4 rows, no sink",
    );
    Ok(())
}

/// The `WarehouseLineageSink` historizes each event as a row in the reserved
/// `lineage_events` table (skade writing skade) — and its self-reference guard
/// drops any event whose output IS `lineage_events`, so appending a lineage row
/// can never recurse.
#[tokio::test]
async fn warehouse_lineage_sink_appends_row_and_self_guards() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    // The sink creates the reserved lineage_events table on first request.
    let sink = wh.lineage_sink().await?;
    let dyn_sink: Arc<dyn LineageSink> = sink.clone();

    // A real event for another table → one appended row.
    let ev = LineageEvent::new(
        Operation::Append,
        DatasetRef::skade("main.orders", Some(11)),
    )
    .with_actor("etl/run-1")
    .with_commit_seq(5);
    dyn_sink.emit(&ev).await?;

    // A self-referential event (output IS the lineage table) → skipped.
    let self_ev = LineageEvent::new(
        Operation::Append,
        DatasetRef::skade("main.lineage_events", Some(99)),
    );
    assert!(
        sink.is_self_reference(&self_ev),
        "guard recognises the self write"
    );
    dyn_sink.emit(&self_ev).await?; // must NOT append (no recursion)

    // Read the lineage_events table back: exactly one row, the non-self event.
    let lt = wh.table("lineage_events").await?;
    let rows = lt.read().await?;
    let total: usize = rows.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total, 1, "one appended row; the self-write was guarded");

    // The row carries the event we emitted.
    let batch = rows.iter().find(|b| b.num_rows() > 0).unwrap();
    let got = LineageEvent::from_arrow_row(batch, 0)?;
    assert_eq!(got.operation, Operation::Append);
    assert_eq!(got.output.table, "main.orders");
    assert_eq!(got.output.snapshot_id, Some(11));
    assert_eq!(got.actor, "etl/run-1");
    assert_eq!(got.commit_seq, Some(5));

    emit_for(
        "skade/lineage",
        "warehouse_lineage_sink_appends_row_and_self_guards",
        total == 1,
        "1 historized row; self-reference write guarded",
    );
    Ok(())
}

/// The `delete_equality` write emits one `Delete` lineage fact on its new
/// snapshot (feature-gated hook), best-effort.
#[tokio::test]
async fn delete_equality_emits_delete_event() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    let sink = CapturingSink::new();
    let mut t = wh
        .create_table("events", &schema())
        .await?
        .with_lineage_sink(Arc::new(sink.clone()));

    t.append(&[batch(&[1, 2, 3])?]).await?; // one Append fact
    assert_eq!(sink.len(), 1);

    // Equality-delete id=2 → one Delete fact on the delete snapshot.
    let key = RecordBatch::try_new(
        Arc::new(Schema::new(vec![Field::new("id", DataType::Int64, false)])),
        vec![Arc::new(Int64Array::from(vec![2i64]))],
    )?;
    t.delete_equality(&key, &["id"]).await?;

    let events = sink.events();
    assert_eq!(events.len(), 2, "append + delete = two facts");
    let del = &events[1];
    assert_eq!(del.operation, Operation::Delete, "second fact is a Delete");
    assert!(del.output.table.ends_with("events"));
    assert_eq!(del.output.snapshot_id, t.current_snapshot_id());
    assert!(del.ts_micros > 0);
    // The delete really committed (a new snapshot became the head); we don't
    // full-scan-merge here (a vendored-iceberg delete_filter bug), the delta
    // path in tests/delta.rs already asserts the delete is readable.
    assert_ne!(
        del.output.snapshot_id,
        Some(events[0].output.snapshot_id.unwrap()),
        "the delete advanced the snapshot past the append"
    );

    emit_for(
        "skade/lineage",
        "delete_equality_emits_delete_event",
        del.operation == Operation::Delete,
        "delete_equality → one Delete lineage fact",
    );
    Ok(())
}

/// An atomic multi-table release emits exactly ONE `Release` lineage event
/// naming all tables in the batch (the batch is one logical job).
#[tokio::test]
async fn atomic_release_emits_one_release_event() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let wh = skade::open(tmp.path().join("lake")).await?;

    // Two tables with a starting append each (so they have a base pointer).
    let mut a = wh.create_table("runs", &schema()).await?;
    let mut b = wh.create_table("components", &schema()).await?;
    a.append(&[batch(&[1])?]).await?;
    b.append(&[batch(&[2])?]).await?;

    let sink = CapturingSink::new();
    let dyn_sink: Arc<dyn LineageSink> = Arc::new(sink.clone());

    // One atomic release advancing BOTH tables (metadata-only property commits).
    let commits = vec![
        (
            wh.table_ident("runs")?,
            Vec::new(),
            vec![TableUpdate::SetProperties {
                updates: [("released".to_string(), "yes".to_string())]
                    .into_iter()
                    .collect(),
            }],
        ),
        (
            wh.table_ident("components")?,
            Vec::new(),
            vec![TableUpdate::SetProperties {
                updates: [("released".to_string(), "yes".to_string())]
                    .into_iter()
                    .collect(),
            }],
        ),
    ];
    let released = wh
        .atomic_release_with_lineage(commits, "nornir/release-7", &dyn_sink)
        .await?;
    assert_eq!(released.len(), 2, "both tables advanced");

    // Exactly one Release event, naming both tables (output + inputs).
    let events = sink.events();
    assert_eq!(events.len(), 1, "one atomic batch = one Release event");
    let rel = &events[0];
    assert_eq!(rel.operation, Operation::Release);
    assert_eq!(rel.actor, "nornir/release-7");
    let mut named: Vec<String> = std::iter::once(rel.output.table.clone())
        .chain(rel.inputs.iter().map(|d| d.table.clone()))
        .collect();
    named.sort();
    assert_eq!(
        named,
        vec!["main.components".to_string(), "main.runs".to_string()],
        "the Release names every table in the batch"
    );

    emit_for(
        "skade/lineage",
        "atomic_release_emits_one_release_event",
        events.len() == 1,
        "atomic_release → one Release event naming all N tables",
    );
    Ok(())
}
